// citrate/core/execution/tests/trace_inspector_neutral.rs
//
// S3-7 (CNV-RPC): the RPC call tracer (`citrate_execution::trace`) is an
// observe-only REVM inspector attached at the RPC/executor boundary
// (`Executor::replay_executor(..).with_call_tracer(..)`). This proves it does
// not change results: the same transactions executed on the same state with
// and without the tracer give the same receipts and the same state root as
// the executor that never saw a tracer, while the tracer records the internal
// CREATE a factory performs.

use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Signature, Transaction};
use citrate_execution::trace::{new_call_tracer, FrameKind};
use citrate_execution::{address_utils, Executor, StateDB};
use primitive_types::U256;
use std::sync::Arc;

const A: [u8; 20] = [0xAA; 20];

fn embedded(addr: [u8; 20]) -> PublicKey {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&addr);
    PublicKey::new(b)
}

/// Factory runtime: CREATE a child returning runtime 0x00, store its address
/// in slot 0, STOP.
fn factory_init() -> Vec<u8> {
    let mut rt = vec![0x6c];
    rt.extend_from_slice(&hex::decode("6001600c60003960016000f300").expect("hex"));
    rt.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x0d, 0x60, 0x13, 0x60, 0x00, 0xf0]);
    rt.extend_from_slice(&[0x60, 0x00, 0x55, 0x00]);
    let len = u8::try_from(rt.len()).expect("short");
    let mut c = vec![
        0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3,
    ];
    c.extend_from_slice(&rt);
    c
}

fn tx(tag: u8, nonce: u64, to: Option<[u8; 20]>, data: Vec<u8>) -> Transaction {
    Transaction {
        hash: Hash::new([tag; 32]),
        nonce,
        from: embedded(A),
        to: to.map(embedded),
        value: 0,
        gas_limit: 1_000_000,
        gas_price: 1_000_000_000,
        data,
        signature: Signature::new([0u8; 64]),
        chain_id: Some(40204),
        ..Default::default()
    }
}

fn block() -> Block {
    BlockBuilder::new()
        .height(1)
        .timestamp(1_700_000_001)
        .build_unhashed()
}

fn funded() -> Executor {
    let e = Executor::with_chain_id(Arc::new(StateDB::new()), 40204);
    e.set_balance(
        &address_utils::normalize_address(&embedded(A)),
        U256::from(1_000_000_000_000_000_000_000u128),
    );
    e
}

#[tokio::test]
async fn a_traced_replay_gives_the_untraced_receipts_and_state_root() {
    let b = block();
    let deploy = tx(1, 0, None, factory_init());

    // The executor that never sees a tracer.
    let plain = funded();
    let r_deploy = plain
        .execute_transaction(&b, &deploy)
        .await
        .expect("deploy");
    let factory: [u8; 20] = r_deploy.output.as_slice().try_into().expect("address");
    let create = tx(2, 1, Some(factory), vec![0x01]);
    let r_create = plain
        .execute_transaction(&b, &create)
        .await
        .expect("create");
    let plain_root = plain.calculate_state_root();

    // Replay executors over the same starting state, with and without a tracer.
    let start = funded();
    let untraced = start.replay_executor(start.state_snapshot(), None);
    let tracer = new_call_tracer();
    let traced = start
        .replay_executor(start.state_snapshot(), None)
        .with_call_tracer(tracer.clone());

    let mut frames = Vec::new();
    let mut touched = citrate_execution::trace::Touched::default();
    for (traced_run, e) in [(false, &untraced), (true, &traced)] {
        let d = e.execute_transaction(&b, &deploy).await.expect("deploy");
        assert_eq!(d.output, r_deploy.output, "same contract address");
        assert_eq!(d.gas_used, r_deploy.gas_used);
        assert_eq!(d.status, r_deploy.status);
        if traced_run {
            frames.push(tracer.lock().take().0);
        }
        let c = e.execute_transaction(&b, &create).await.expect("create");
        assert_eq!(c.gas_used, r_create.gas_used);
        assert_eq!(c.status, r_create.status);
        assert_eq!(c.output, r_create.output);
        assert_eq!(c.logs.len(), r_create.logs.len());
        if traced_run {
            let (f, t) = tracer.lock().take();
            frames.push(f);
            touched = t;
        }
    }
    assert_eq!(untraced.calculate_state_root(), plain_root);
    assert_eq!(
        traced.calculate_state_root(),
        plain_root,
        "tracing changed the state root"
    );

    // And the tracer saw the work, one top-level frame per transaction (the
    // frames of the committed attempt only, even when the MVCC fast path
    // aborted and re-ran an attempt): a CREATE (the deploy), then a CALL to
    // the factory with an inner CREATE.
    assert_eq!(
        frames[0].len(),
        1,
        "one frame for the deploy: {:?}",
        frames[0]
    );
    assert_eq!(
        frames[1].len(),
        1,
        "one frame for the call: {:?}",
        frames[1]
    );
    let roots = vec![frames[0][0].clone(), frames[1][0].clone()];
    assert_eq!(roots[0].kind, FrameKind::Create);
    assert_eq!(roots[0].to, Some(factory));
    assert_eq!(roots[1].kind, FrameKind::Call);
    assert_eq!(roots[1].calls.len(), 1);
    assert_eq!(roots[1].calls[0].kind, FrameKind::Create);
    assert_eq!(roots[1].calls[0].from, factory);
    let child = roots[1].calls[0].to.expect("child address");
    assert!(touched.accounts.contains(&child));
    assert!(touched
        .slots
        .get(&factory)
        .is_some_and(|s| s.contains(&[0u8; 32])));

    // The consensus-style executor (`plain`) never had a tracer: replaying on
    // it again leaves its root where it was.
    assert_eq!(plain.calculate_state_root(), plain_root);
}
