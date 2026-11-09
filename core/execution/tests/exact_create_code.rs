// citrate/core/execution/tests/exact_create_code.rs
//
// Code storage for contracts created from inside a call (`crate::exact_code`).
//
// Every test runs real transactions through `Executor::execute_transaction`,
// the entry point block production and import use (journal, MVCC commit,
// drain), then reads the result back the way `eth_getCode` does (the account's
// code hash, then the code store) and the way contract code does (EXTCODESIZE,
// EXTCODEHASH and EXTCODECOPY from a probe contract in a LATER transaction, so
// the values come from committed state, not from REVM's in-transaction
// journal).
//
// Covered:
//   * a factory that CREATEs and CREATE2s a child from a call;
//   * a constructor that CREATEs a child;
//   * a top-level create transaction (exact on both sides of the activation);
//   * precompile addresses (no code, unchanged by the rule), and a created
//     child that itself calls a precompile;
//   * the legacy rule below the activation: the padded bytes, and a state root
//     pinned to the value the previous binary produces for the same block.
//
// The activation height is process-global; this file is its own test binary,
// so every test sets the SAME height and only the block number varies.

use citrate_consensus::types::{
    Block, BlockBuilder, Hash, PublicKey, Signature, Transaction as ConsensusTransaction, VrfProof,
};
use citrate_execution::exact_code::set_exact_create_code_height;
use citrate_execution::{address_utils, types::*, Executor, StateDB};
use primitive_types::U256;
use sha3::{Digest, Keccak256};
use std::sync::Arc;

const ACTIVATION: u64 = 200;
/// Below the activation: the legacy (padded) rule.
const LEGACY: u64 = 100;
/// At/after the activation: the exact rule.
const EXACT: u64 = 300;
/// revm's analysed bytecode carries this many trailing zero bytes.
const REVM_PADDING: usize = 33;

fn activate() {
    set_exact_create_code_height(Some(ACTIVATION));
}

fn keccak(b: &[u8]) -> [u8; 32] {
    Keccak256::digest(b).into()
}

// ---------------------------------------------------------------------------
// Bytecode
// ---------------------------------------------------------------------------

/// The child's runtime code: returns 42, then a JUMPDEST and a PUSH32 whose
/// immediate runs off the end of the code (the shape interpreter padding
/// exists for).
fn child_runtime() -> Vec<u8> {
    vec![
        0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3, // mstore(0, 42) return(0, 32)
        0x5b, 0x7f, 0xaa, 0xbb,
    ]
}

/// Init code that returns `runtime` as the deployed code.
fn init_for(runtime: &[u8]) -> Vec<u8> {
    let len = u8::try_from(runtime.len()).expect("short runtime");
    // PUSH1 len DUP1 PUSH1 off PUSH0 CODECOPY PUSH0 RETURN
    let mut c = vec![0x60, len, 0x80, 0x60, 0x09, 0x5f, 0x39, 0x5f, 0xf3];
    c.extend_from_slice(runtime);
    c
}

/// Factory runtime. Calldata = `mode (1 byte) || init code`. Mode 2 runs
/// CREATE2 with salt 0, anything else CREATE. Returns the new address as a
/// 32-byte word.
fn factory_runtime() -> Vec<u8> {
    let mut c = vec![
        0x36, 0x60, 0x01, 0x90, 0x03, // n = calldatasize - 1
        0x80, 0x60, 0x01, 0x5f, 0x37, // calldatacopy(0, 1, n)
        0x5f, 0x35, 0x60, 0xf8, 0x1c, // mode = calldata[0]
        0x60, 0x02, 0x14, // mode == 2
        0x60, 0x00, 0x57, // PUSH1 <create2> JUMPI   (patched)
        0x5f, 0x5f, 0xf0, // create(0, 0, n)
        0x60, 0x00, 0x56, // PUSH1 <ret> JUMP       (patched)
    ];
    let create2 = c.len();
    c.extend_from_slice(&[0x5b, 0x5f, 0x90, 0x5f, 0x5f, 0xf5]); // create2(0, 0, n, 0)
    let ret = c.len();
    c.extend_from_slice(&[0x5b, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]); // return addr
    c[19] = create2 as u8;
    c[25] = ret as u8;
    c
}

/// Probe runtime. Calldata = the address as a word. Returns
/// `EXTCODESIZE (32) || EXTCODEHASH (32) || EXTCODECOPY(all)`.
fn probe_runtime() -> Vec<u8> {
    vec![
        0x5f, 0x35, // a
        0x80, 0x3b, // sz a
        0x80, 0x5f, 0x52, // mstore(0, sz)
        0x81, 0x3f, 0x60, 0x20, 0x52, // mstore(0x20, extcodehash(a))
        0x80, 0x5f, 0x60, 0x40, 0x84, 0x3c, // extcodecopy(a, 0x40, 0, sz)
        0x60, 0x40, 0x01, 0x5f, 0xf3, // return(0, sz + 0x40)
    ]
}

/// Init code whose constructor CREATEs a child from `child_init`, stores the
/// child's address in slot 0, and deploys a runtime that returns slot 0.
fn parent_init(child_init: &[u8]) -> Vec<u8> {
    // Runtime: sload(0) -> mstore(0) -> return(0, 32)
    let runtime = vec![0x5f, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
    let cl = u8::try_from(child_init.len()).expect("short child init");
    let rl = u8::try_from(runtime.len()).expect("short runtime");
    // Prefix with placeholder offsets, patched below.
    let mut c = vec![
        0x60, cl, 0x60, 0x00, 0x5f, 0x39, // codecopy(0, child_off, cl)
        0x60, cl, 0x5f, 0x5f, 0xf0, // create(0, 0, cl)
        0x5f, 0x55, // sstore(0, child)
        0x60, rl, 0x80, 0x60, 0x00, 0x5f, 0x39, // codecopy(0, rt_off, rl)
        0x5f, 0xf3, // return(0, rl)
    ];
    let child_off = c.len();
    let rt_off = child_off + child_init.len();
    c[3] = child_off as u8;
    c[17] = rt_off as u8;
    c.extend_from_slice(child_init);
    c.extend_from_slice(&runtime);
    c
}

/// A child runtime that calls the IDENTITY precompile (0x04) on a word and
/// returns the precompile's output.
fn precompile_caller_runtime() -> Vec<u8> {
    vec![
        0x60, 0x77, 0x5f, 0x52, // mstore(0, 0x77)
        // staticcall(gas, 4, 0, 32, 0x20, 32)
        0x60, 0x20, 0x60, 0x20, 0x60, 0x20, 0x5f, 0x60, 0x04, 0x5a, 0xfa, 0x50, // pop success
        0x60, 0x20, 0x60, 0x20, 0xf3, // return(0x20, 32)
    ]
}

// ---------------------------------------------------------------------------
// Execution harness
// ---------------------------------------------------------------------------

fn embed(addr: Address) -> PublicKey {
    let mut pk = [0u8; 32];
    pk[..20].copy_from_slice(&addr.0);
    PublicKey::new(pk)
}

fn sender_pk() -> PublicKey {
    let mut pk = [0u8; 32];
    pk[0] = 0xC0;
    PublicKey::new(pk)
}

fn block_at(height: u64) -> Block {
    BlockBuilder::new()
        .hash(Hash::new([0xC0; 32]))
        .height(height)
        .timestamp(1_700_000_000)
        .blue_score(10)
        .blue_work(1000)
        .vrf_reveal(VrfProof {
            proof: vec![0u8; 80],
            output: Hash::default(),
        })
        .build_unhashed()
}

struct Chain {
    executor: Executor,
    block: Block,
    nonce: u64,
}

impl Chain {
    fn at(height: u64) -> Self {
        let executor = Executor::new(Arc::new(StateDB::new()));
        let sender = address_utils::normalize_address(&sender_pk());
        executor.set_balance(&sender, U256::from(10u64).pow(U256::from(24u64)));
        Self {
            executor,
            block: block_at(height),
            nonce: 0,
        }
    }

    fn tx(&mut self, to: Option<Address>, data: Vec<u8>) -> ConsensusTransaction {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&self.nonce.to_be_bytes());
        h[31] = 0xC0;
        let tx = ConsensusTransaction {
            hash: Hash::new(h),
            nonce: self.nonce,
            from: sender_pk(),
            to: to.map(embed),
            value: 0,
            gas_limit: 3_000_000,
            gas_price: 1,
            data,
            signature: Signature::new([0u8; 64]),
            tx_type: None,
            ..Default::default()
        };
        self.nonce += 1;
        tx
    }

    async fn send(&mut self, to: Option<Address>, data: Vec<u8>) -> TransactionReceipt {
        let tx = self.tx(to, data);
        let r = self
            .executor
            .execute_transaction(&self.block, &tx)
            .await
            .expect("transaction executes");
        assert!(r.status, "transaction succeeds: {:?}", r.revert_reason);
        r
    }

    async fn deploy(&mut self, runtime: &[u8]) -> Address {
        self.deploy_init(init_for(runtime)).await
    }

    async fn deploy_init(&mut self, init: Vec<u8>) -> Address {
        let r = self.send(None, init).await;
        let mut a = [0u8; 20];
        a.copy_from_slice(&r.output[..20]);
        Address(a)
    }

    /// Call `to` and read the last 20 bytes of the returned word as an address.
    async fn call_for_address(&mut self, to: Address, data: Vec<u8>) -> Address {
        let r = self.send(Some(to), data).await;
        assert_eq!(r.output.len(), 32, "an address word");
        let mut a = [0u8; 20];
        a.copy_from_slice(&r.output[12..32]);
        assert_ne!(a, [0u8; 20], "the create succeeded");
        Address(a)
    }

    /// `eth_getCode`: the account's code hash, then the code store.
    fn stored_code(&self, addr: &Address) -> Vec<u8> {
        let h = self.executor.get_code_hash(addr);
        if h == Hash::default() {
            return Vec::new();
        }
        self.executor
            .state_db()
            .get_code(&h)
            .expect("code for the account's code hash")
    }

    fn stored_code_hash(&self, addr: &Address) -> [u8; 32] {
        *self.executor.get_code_hash(addr).as_bytes()
    }

    /// EXTCODESIZE, EXTCODEHASH and EXTCODECOPY from contract code, in a new
    /// transaction.
    async fn probe(&mut self, probe: Address, target: Address) -> (u64, [u8; 32], Vec<u8>) {
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&target.0);
        let out = self.send(Some(probe), word.to_vec()).await.output;
        let mut sz = [0u8; 8];
        sz.copy_from_slice(&out[24..32]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&out[32..64]);
        (u64::from_be_bytes(sz), hash, out[64..].to_vec())
    }
}

fn mode(m: u8, init: &[u8]) -> Vec<u8> {
    let mut d = vec![m];
    d.extend_from_slice(init);
    d
}

/// Every view of `addr`'s code agrees with `expected`, byte for byte.
async fn assert_exact(
    chain: &mut Chain,
    probe: Address,
    addr: Address,
    expected: &[u8],
    what: &str,
) {
    let stored = chain.stored_code(&addr);
    assert_eq!(
        stored.len(),
        expected.len(),
        "{what}: eth_getCode length (stored {} bytes, original {})",
        stored.len(),
        expected.len()
    );
    assert_eq!(stored, expected, "{what}: eth_getCode bytes");
    assert_eq!(
        chain.stored_code_hash(&addr),
        keccak(expected),
        "{what}: the account's code hash is keccak(original)"
    );
    let (size, hash, copied) = chain.probe(probe, addr).await;
    assert_eq!(size, expected.len() as u64, "{what}: EXTCODESIZE");
    assert_eq!(hash, keccak(expected), "{what}: EXTCODEHASH");
    assert_eq!(
        hash,
        keccak(&stored),
        "{what}: keccak(eth_getCode) == EXTCODEHASH"
    );
    assert_eq!(copied, expected, "{what}: EXTCODECOPY");
}

// ---------------------------------------------------------------------------
// After the activation: exact
// ---------------------------------------------------------------------------

#[tokio::test]
async fn factory_create_stores_the_original_runtime() {
    activate();
    let mut chain = Chain::at(EXACT);
    let probe = chain.deploy(&probe_runtime()).await;
    let factory = chain.deploy(&factory_runtime()).await;
    let child = chain
        .call_for_address(factory, mode(1, &init_for(&child_runtime())))
        .await;
    assert_exact(&mut chain, probe, child, &child_runtime(), "CREATE child").await;
    // And the code runs.
    let out = chain.send(Some(child), vec![0x01]).await.output;
    assert_eq!(out[31], 42);
}

#[tokio::test]
async fn factory_create2_stores_the_original_runtime() {
    activate();
    let mut chain = Chain::at(EXACT);
    let probe = chain.deploy(&probe_runtime()).await;
    let factory = chain.deploy(&factory_runtime()).await;
    let init = init_for(&child_runtime());
    let child = chain.call_for_address(factory, mode(2, &init)).await;

    // The CREATE2 address is the standard one.
    let mut pre = vec![0xffu8];
    pre.extend_from_slice(&factory.0);
    pre.extend_from_slice(&[0u8; 32]);
    pre.extend_from_slice(&keccak(&init));
    assert_eq!(&child.0[..], &keccak(&pre)[12..], "CREATE2 address");

    assert_exact(&mut chain, probe, child, &child_runtime(), "CREATE2 child").await;
}

#[tokio::test]
async fn constructor_create_stores_the_original_runtime() {
    activate();
    let mut chain = Chain::at(EXACT);
    let probe = chain.deploy(&probe_runtime()).await;
    let parent = chain
        .deploy_init(parent_init(&init_for(&child_runtime())))
        .await;
    let child = chain.call_for_address(parent, vec![0x01]).await;
    assert_exact(
        &mut chain,
        probe,
        child,
        &child_runtime(),
        "constructor child",
    )
    .await;
}

#[tokio::test]
async fn top_level_create_is_exact_on_both_sides_of_the_activation() {
    activate();
    for height in [LEGACY, EXACT] {
        let mut chain = Chain::at(height);
        let probe = chain.deploy(&probe_runtime()).await;
        let factory = chain.deploy(&factory_runtime()).await;
        assert_exact(
            &mut chain,
            probe,
            factory,
            &factory_runtime(),
            &format!("top-level create at {height}"),
        )
        .await;
    }
}

#[tokio::test]
async fn precompiles_have_no_code_and_a_created_precompile_caller_is_exact() {
    activate();
    let mut chain = Chain::at(EXACT);
    let probe = chain.deploy(&probe_runtime()).await;
    for pc in [0x0001u16, 0x0004, 0x0108] {
        let mut a = [0u8; 20];
        a[18] = (pc >> 8) as u8;
        a[19] = (pc & 0xff) as u8;
        let (size, hash, copied) = chain.probe(probe, Address(a)).await;
        assert_eq!(size, 0, "precompile 0x{pc:04x} has no code");
        assert!(copied.is_empty());
        assert_eq!(
            hash, [0u8; 32],
            "precompile 0x{pc:04x} EXTCODEHASH (empty account)"
        );
    }
    let factory = chain.deploy(&factory_runtime()).await;
    let caller = chain
        .call_for_address(factory, mode(2, &init_for(&precompile_caller_runtime())))
        .await;
    assert_exact(
        &mut chain,
        probe,
        caller,
        &precompile_caller_runtime(),
        "created precompile caller",
    )
    .await;
    let out = chain.send(Some(caller), vec![0x01]).await.output;
    assert_eq!(out[31], 0x77, "the created code still calls IDENTITY");
}

// ---------------------------------------------------------------------------
// Below the activation: the legacy rule, unchanged
// ---------------------------------------------------------------------------

/// The scenario the replay pin covers: probe, factory, a CREATE child and a
/// CREATE2 child, all at `LEGACY`.
async fn legacy_scenario() -> (Chain, Address, Address) {
    let mut chain = Chain::at(LEGACY);
    let _probe = chain.deploy(&probe_runtime()).await;
    let factory = chain.deploy(&factory_runtime()).await;
    let init = init_for(&child_runtime());
    let c1 = chain.call_for_address(factory, mode(1, &init)).await;
    let c2 = chain.call_for_address(factory, mode(2, &init)).await;
    (chain, c1, c2)
}

/// The state root the previous binary (no exact-code rule) computes for
/// `legacy_scenario`. Captured by running this scenario on the parent commit.
const LEGACY_SCENARIO_ROOT: &str =
    "303ce59265c76bb379997b167a1fdee33aa00978a4e9b9dd0088b79d40f5f71d";

#[tokio::test]
async fn below_activation_the_padded_form_and_the_state_root_are_unchanged() {
    activate();
    let (chain, c1, c2) = legacy_scenario().await;
    let mut padded = child_runtime();
    padded.extend_from_slice(&[0u8; REVM_PADDING]);
    for (what, c) in [("CREATE", c1), ("CREATE2", c2)] {
        assert_eq!(
            chain.stored_code(&c),
            padded,
            "{what} child below the activation keeps the legacy padded form"
        );
        assert_eq!(chain.stored_code_hash(&c), keccak(&padded));
    }
    let root = hex::encode(chain.executor.calculate_state_root().as_bytes());
    assert_eq!(
        root, LEGACY_SCENARIO_ROOT,
        "below the activation the state root equals the previous binary's"
    );
}

#[tokio::test]
async fn the_rule_changes_the_state_root_only_through_created_code() {
    activate();
    // Same transactions, legacy vs exact height: the roots differ (the rule is
    // consensus-visible), and the only per-account difference is the children's
    // code hash.
    let (legacy, l1, l2) = legacy_scenario().await;
    let mut exact = Chain::at(EXACT);
    let _p = exact.deploy(&probe_runtime()).await;
    let f = exact.deploy(&factory_runtime()).await;
    let init = init_for(&child_runtime());
    let e1 = exact.call_for_address(f, mode(1, &init)).await;
    let e2 = exact.call_for_address(f, mode(2, &init)).await;
    assert_eq!((l1, l2), (e1, e2), "same addresses");
    assert_ne!(
        legacy.executor.calculate_state_root(),
        exact.executor.calculate_state_root()
    );
    assert_eq!(exact.stored_code_hash(&e1), keccak(&child_runtime()));
    assert_ne!(legacy.stored_code_hash(&l1), exact.stored_code_hash(&e1));
    assert_eq!(
        legacy.executor.get_nonce(&l1),
        exact.executor.get_nonce(&e1)
    );
    assert_eq!(
        legacy.executor.get_balance(&l2),
        exact.executor.get_balance(&e2)
    );
}

/// A top-level deploy whose constructor CREATEs a child, all at `LEGACY`. The
/// contract-creation entry point (not the call entry point) runs the
/// constructor, so this pins that entry point's activation gate.
async fn legacy_constructor_scenario() -> (Chain, Address) {
    let mut chain = Chain::at(LEGACY);
    let _probe = chain.deploy(&probe_runtime()).await;
    let parent = chain
        .deploy_init(parent_init(&init_for(&child_runtime())))
        .await;
    let child = chain.call_for_address(parent, vec![0x01]).await;
    (chain, child)
}

/// The state root the previous binary (no exact-code rule) computes for
/// `legacy_constructor_scenario`. Captured by running the same transactions
/// on `main` before the rule existed.
const LEGACY_CONSTRUCTOR_SCENARIO_ROOT: &str =
    "ab68f3878933c60dbb57351d4c0d73d62a32755ac20ecfae531a0be2d9337290";

#[tokio::test]
async fn below_activation_a_constructor_create_keeps_the_padded_form_and_the_state_root() {
    activate();
    let (chain, child) = legacy_constructor_scenario().await;
    let mut padded = child_runtime();
    padded.extend_from_slice(&[0u8; REVM_PADDING]);
    assert_eq!(
        chain.stored_code(&child),
        padded,
        "a constructor-created child below the activation keeps the legacy padded form"
    );
    assert_eq!(chain.stored_code_hash(&child), keccak(&padded));
    let root = hex::encode(chain.executor.calculate_state_root().as_bytes());
    assert_eq!(
        root, LEGACY_CONSTRUCTOR_SCENARIO_ROOT,
        "below the activation the state root equals the previous binary's"
    );
}
