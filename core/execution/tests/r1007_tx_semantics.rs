//! r1007 transaction semantics (spec 06 §3.12, owner decisions 2026-11-09)
//! and the nonce rule duplicate suppression rests on (§3.5, reviewer R10).
//!
//! T1: a call with calldata to an account that has no code runs in the EVM:
//!     value moves and the gas is `CALL_BASE + EVM gas`.
//! T2: a deployment's value moves to the created contract.
//! Both are gated by `supply_hardening`; below its height the legacy rule
//! (nothing runs and no value moves; a deployment's value is checked, never
//! transferred) is pinned unchanged, so r1006 replays byte for byte.
//!
//! R10: every transaction the executor EXECUTES (class C or D: a receipt,
//! success or failure) moves its sender's nonce by exactly one, for every
//! transaction type the parser produces; a skipped one moves nothing.
//!
//! The supply-hardening height is process-wide; this file is its own test
//! binary and every test publishes the same height under one lock.

use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction as ConsensusTransaction,
};
use citrate_execution::supply_hardening::set_supply_hardening_height;
use citrate_execution::types::{Address, ExecutionError, TransactionReceipt};
use citrate_execution::{address_utils, Executor, StateDB};
use primitive_types::U256;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

/// supply_hardening activation for this binary.
const ACT: u64 = 200;
/// A height below it (r1006 history) and one at/above it (r1007).
const LEGACY: u64 = 100;
const R1007: u64 = 300;
const PRICE: u64 = 1_000_000_000;
const VALUE: u128 = 7_000_000;
/// The Citrate base charges taken before the EVM runs (§3.12).
const CALL_BASE: u64 = 700;
const CREATE_BASE: u64 = 32_000;

static GATE: Mutex<()> = Mutex::const_new(());

async fn gate() -> MutexGuard<'static, ()> {
    let g = GATE.lock().await;
    set_supply_hardening_height(Some(ACT));
    g
}

fn pk(seed: u8) -> PublicKey {
    let mut b = [0u8; 32];
    b[0] = seed;
    b[1] = 0x5E;
    PublicKey::new(b)
}

fn embed(a: Address) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&a.0);
    PublicKey::new(b)
}

fn block_at(height: u64) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([0xB1; 32]))
        .height(height)
        .timestamp(1_700_000_000)
        .build_unhashed()
}

/// Runtime `0x00` (STOP) behind init code that returns it.
const STOP_INIT: [u8; 10] = [0x60, 0x00, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xF3];
/// Init code that reverts.
const REVERT_INIT: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xFD];
/// A contract whose every call reverts, and one that stores 1 at slot 0.
const REVERTER: Address = Address([0xEF; 20]);
const REVERTER_CODE: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xFD];
const STORER: Address = Address([0x5D; 20]);
const STORER_CODE: [u8; 6] = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];

struct Chain {
    exec: Executor,
    from: PublicKey,
    salt: u8,
}

impl Chain {
    fn new(seed: u8) -> Self {
        let exec = Executor::new(Arc::new(StateDB::new()));
        let from = pk(seed);
        exec.set_balance(
            &address_utils::normalize_address(&from),
            U256::from(10u64).pow(U256::from(24u64)),
        );
        exec.set_code(&REVERTER, REVERTER_CODE.to_vec());
        exec.set_code(&STORER, STORER_CODE.to_vec());
        Self {
            exec,
            from,
            salt: 0,
        }
    }

    fn sender(&self) -> Address {
        address_utils::normalize_address(&self.from)
    }

    fn nonce(&self) -> u64 {
        self.exec.get_nonce(&self.sender())
    }

    fn tx(
        &mut self,
        nonce: u64,
        to: Option<PublicKey>,
        value: u128,
        data: Vec<u8>,
        gas: u64,
    ) -> ConsensusTransaction {
        self.salt = self.salt.wrapping_add(1);
        let mut h = [0u8; 32];
        h[0] = self.from.as_bytes()[0];
        h[1..9].copy_from_slice(&nonce.to_be_bytes());
        h[9] = self.salt;
        ConsensusTransaction {
            hash: Hash::new(h),
            nonce,
            from: self.from,
            to,
            value,
            gas_limit: gas,
            gas_price: PRICE,
            data,
            signature: Signature::new([0; 64]),
            tx_type: None,
            ..Default::default()
        }
    }

    async fn run(
        &self,
        height: u64,
        tx: &ConsensusTransaction,
    ) -> Result<TransactionReceipt, ExecutionError> {
        self.exec.execute_transaction(&block_at(height), tx).await
    }
}

fn wei(gas: u64) -> U256 {
    U256::from(gas) * U256::from(PRICE)
}

/// T1 at r1007: the call runs in the EVM. The recipient is paid, the sender
/// pays the value and `CALL_BASE + 21,000 + 16 per non-zero calldata byte`.
#[tokio::test]
async fn codeless_call_with_calldata_moves_value_and_pays_evm_gas() {
    let _g = gate().await;
    let mut c = Chain::new(0xA1);
    let to = Address([0x7A; 20]);
    let before = c.exec.get_balance(&c.sender());
    let tx = c.tx(0, Some(embed(to)), VALUE, vec![1, 2, 3], 100_000);
    let r = c.run(R1007, &tx).await.expect("executed");
    assert!(r.status, "{:?}", r.revert_reason);
    let gas = CALL_BASE + 21_000 + 3 * 16;
    assert_eq!(r.gas_used, gas, "EVM gas for a call to an empty account");
    assert_eq!(
        c.exec.get_balance(&to),
        U256::from(VALUE),
        "the value moved"
    );
    assert_eq!(
        c.exec.get_balance(&c.sender()),
        before - U256::from(VALUE) - wei(gas)
    );
    assert_eq!(c.nonce(), 1);
}

/// T1 below supply hardening (r1006 history), pinned: nothing runs, nothing
/// moves, the base charge only.
#[tokio::test]
async fn codeless_call_below_supply_hardening_keeps_the_legacy_rule() {
    let _g = gate().await;
    let mut c = Chain::new(0xA2);
    let to = Address([0x7B; 20]);
    let before = c.exec.get_balance(&c.sender());
    let tx = c.tx(0, Some(embed(to)), VALUE, vec![1, 2, 3], 100_000);
    let r = c.run(LEGACY, &tx).await.expect("executed");
    assert!(r.status);
    assert_eq!(r.gas_used, CALL_BASE);
    assert_eq!(c.exec.get_balance(&to), U256::zero(), "no value moved");
    assert_eq!(c.exec.get_balance(&c.sender()), before - wei(CALL_BASE));
}

/// T2 at r1007: the created contract holds the deployment's value; the
/// sender paid it once, plus gas.
#[tokio::test]
async fn deployment_value_moves_to_the_created_contract() {
    let _g = gate().await;
    let mut c = Chain::new(0xA3);
    let before = c.exec.get_balance(&c.sender());
    let tx = c.tx(0, None, VALUE, STOP_INIT.to_vec(), 200_000);
    let r = c.run(R1007, &tx).await.expect("executed");
    assert!(r.status, "{:?}", r.revert_reason);
    let mut created = [0u8; 20];
    created.copy_from_slice(&r.output[..20]);
    let created = Address(created);
    assert_eq!(c.exec.get_balance(&created), U256::from(VALUE));
    assert_eq!(
        c.exec.get_balance(&c.sender()),
        before - U256::from(VALUE) - wei(r.gas_used)
    );
    assert!(r.gas_used > CREATE_BASE);
}

/// T2 below supply hardening, pinned: the value is checked, not moved.
#[tokio::test]
async fn deployment_value_below_supply_hardening_keeps_the_legacy_rule() {
    let _g = gate().await;
    let mut c = Chain::new(0xA4);
    let before = c.exec.get_balance(&c.sender());
    let tx = c.tx(0, None, VALUE, STOP_INIT.to_vec(), 200_000);
    let r = c.run(LEGACY, &tx).await.expect("executed");
    assert!(r.status);
    let mut created = [0u8; 20];
    created.copy_from_slice(&r.output[..20]);
    assert_eq!(c.exec.get_balance(&Address(created)), U256::zero());
    assert_eq!(c.exec.get_balance(&c.sender()), before - wei(r.gas_used));
}

/// R10 (spec 06 §3.5): every executed transaction (a receipt, status 1 or 0)
/// moves its sender's nonce by exactly one, for each type the parser
/// produces, at both rule sets; a skipped one (wrong nonce, unaffordable,
/// undecodable) moves nothing and returns no receipt.
#[tokio::test]
async fn every_executed_tx_type_bumps_nonce() {
    let _g = gate().await;
    let model_precompile = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        Address(a)
    };
    let artifact_precompile = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x02;
        Address(a)
    };
    let governance_precompile = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x03;
        Address(a)
    };
    let model_hash = [0x4D; 32];
    let register = {
        let meta = serde_json::to_vec(&serde_json::json!({
            "name": "R10 model", "version": "1.0.0", "description": "nonce rule",
            "framework": "onnx", "input_shape": [1], "output_shape": [1], "size_bytes": 1
        }))
        .expect("metadata");
        let mut d = vec![0x01, 0x00, 0x00, 0x00];
        d.extend_from_slice(&model_hash);
        d.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        d.extend_from_slice(&meta);
        d.push(0); // AccessPolicy::Public
        d
    };
    let update = {
        let meta = serde_json::to_vec(&serde_json::json!({"name": "R10 model v2"})).expect("meta");
        let mut d = vec![0x03, 0x00, 0x00, 0x00];
        d.extend_from_slice(&model_hash);
        d.extend_from_slice(&(meta.len() as u32).to_be_bytes());
        d.extend_from_slice(&meta);
        d
    };
    let inference = {
        let mut d = vec![0x02, 0x00, 0x00, 0x00];
        d.extend_from_slice(&model_hash);
        d.extend_from_slice(&[9, 9, 9]);
        d
    };
    let ai_to = Some(pk(0x10));
    // (name, to, value, data, gas): every shape `parse_transaction_type`
    // accepts, succeeding and failing.
    type Case<'a> = (&'a str, Option<PublicKey>, u128, Vec<u8>, u64);
    let cases: Vec<Case> = vec![
        (
            "transfer",
            Some(embed(Address([0x71; 20]))),
            VALUE,
            vec![],
            21_000,
        ),
        (
            "transfer out of gas",
            Some(embed(Address([0x71; 20]))),
            VALUE,
            vec![],
            20_000,
        ),
        ("self transfer", None, 0, vec![], 21_000),
        ("deploy", None, 0, STOP_INIT.to_vec(), 200_000),
        (
            "deploy that reverts",
            None,
            0,
            REVERT_INIT.to_vec(),
            200_000,
        ),
        (
            "deploy below its base charge",
            None,
            0,
            STOP_INIT.to_vec(),
            30_000,
        ),
        (
            "call that writes storage",
            Some(embed(STORER)),
            0,
            vec![1],
            100_000,
        ),
        (
            "call that reverts",
            Some(embed(REVERTER)),
            0,
            vec![1],
            100_000,
        ),
        ("call out of gas", Some(embed(STORER)), 0, vec![1], 21_800),
        (
            "call to an account without code",
            Some(embed(Address([0x72; 20]))),
            VALUE,
            vec![1],
            100_000,
        ),
        (
            "model precompile, bad input",
            Some(embed(model_precompile)),
            0,
            vec![0xFF],
            100_000,
        ),
        (
            "artifact precompile",
            Some(embed(artifact_precompile)),
            0,
            vec![1],
            100_000,
        ),
        (
            "governance precompile, bad input",
            Some(embed(governance_precompile)),
            0,
            vec![0xFF],
            100_000,
        ),
        ("register model", ai_to, 0, register, 2_000_000),
        ("update model", ai_to, 0, update, 2_000_000),
        ("inference request", ai_to, 0, inference, 2_000_000),
    ];
    for height in [LEGACY, R1007] {
        for (i, (name, to, value, data, gas)) in cases.iter().enumerate() {
            let mut c = Chain::new(0x20 + i as u8);
            // A self transfer is a transfer to the sender.
            let to = if *name == "self transfer" {
                Some(c.from)
            } else {
                *to
            };
            // The AI cases that need a registered model get one first.
            if name.starts_with("update") || name.starts_with("inference") {
                let reg = c.tx(0, ai_to, 0, cases[13].3.clone(), 2_000_000);
                c.run(height, &reg).await.expect("register runs");
            }
            let n = c.nonce();
            let tx = c.tx(n, to, *value, data.clone(), *gas);
            let r = c
                .run(height, &tx)
                .await
                .unwrap_or_else(|e| panic!("{name} @ {height}: not executed: {e}"));
            assert_eq!(
                c.nonce(),
                n + 1,
                "{name} @ {height} (status {}): an executed tx moves the nonce by one",
                r.status
            );
            // The same transaction again is a skip: no receipt, no nonce.
            let again = c.run(height, &tx).await;
            assert!(
                matches!(again, Err(ExecutionError::InvalidNonce { .. })),
                "{name} @ {height}: a duplicate is a nonce skip: {again:?}"
            );
            assert_eq!(c.nonce(), n + 1, "{name} @ {height}: a skip moves nothing");
        }
        // Unaffordable and undecodable: skipped, nothing moves.
        let mut c = Chain::new(0x60);
        let poor = Chain::new(0x61).from;
        let mut t = c.tx(0, Some(embed(Address([0x73; 20]))), 1, vec![], 21_000);
        t.from = poor;
        let exec_poor = Executor::new(Arc::new(StateDB::new()));
        assert!(matches!(
            exec_poor.execute_transaction(&block_at(height), &t).await,
            Err(ExecutionError::InsufficientBalance { .. })
        ));
        assert_eq!(
            exec_poor.get_nonce(&address_utils::normalize_address(&poor)),
            0
        );
        let undecodable = c.tx(0, None, 0, vec![], 21_000);
        assert!(
            c.run(height, &undecodable).await.is_err(),
            "no recipient, no code"
        );
        assert_eq!(c.nonce(), 0, "an undecodable tx moves nothing");
    }
}
